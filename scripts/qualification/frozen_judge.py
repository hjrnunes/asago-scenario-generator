"""The package-declared, bounded semantic judge seam."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class FrozenJudgeResult:
    verdict: str
    evidence_refs: tuple[str, ...]
    reason: str
    request: dict[str, Any] | None
    dispatched: bool
    reused: bool = False
    output: Any = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "evidence_refs": list(self.evidence_refs),
            "reason": self.reason,
            "request": self.request,
            "output": self.output,
            "dispatched": self.dispatched,
            "reused": self.reused,
        }


def evaluate_frozen_judge(
    spec: dict[str, Any] | None,
    evidence: dict[str, Any],
    *,
    client: Callable[[dict[str, Any]], dict[str, Any]] | None,
    reuse: dict[str, dict[str, Any]] | None = None,
) -> FrozenJudgeResult:
    """Dispatch once only when a valid package judge spec exists."""

    if spec is None:
        return FrozenJudgeResult("unresolved", (), "judge_not_declared", None, False)
    if not isinstance(spec, dict) or not isinstance(spec.get("question"), str):
        return FrozenJudgeResult("unresolved", (), "judge_spec_invalid", None, False)
    request = {
        "question": spec["question"],
        "criteria": spec.get("criteria", []),
        "facts": spec.get("facts", []),
        "runtime_facts": dict(evidence.get("bindings", {}))
        if isinstance(evidence.get("bindings", {}), dict)
        else {},
        "runtime_fact_provenance": dict(evidence.get("binding_provenance", {}))
        if isinstance(evidence.get("binding_provenance", {}), dict)
        else {},
        "evidence": evidence,
    }
    key = _digest(request)
    if reuse and key in reuse:
        saved = reuse[key]
        response = {
            "verdict": saved.get("verdict", "unresolved"),
            "evidence_refs": saved.get("evidence_refs", []),
        }
        result = _validate_response(response, request, dispatched=False)
        return FrozenJudgeResult(
            result[0],
            result[1],
            "judge_reused" if result[2] == "judge_completed" else result[2],
            request,
            False,
            True,
            response,
        )
    if client is None:
        return FrozenJudgeResult("unresolved", (), "judge_unavailable", request, False)
    try:
        response = client(request)
    except Exception as exc:  # pragma: no cover - transport boundary
        return FrozenJudgeResult(
            "unresolved", (), f"judge_failed:{type(exc).__name__}", request, True
        )
    if not isinstance(response, dict):
        return FrozenJudgeResult(
            "unresolved", (), "judge_response_invalid", request, True, False, response
        )
    result = _validate_response(response, request, dispatched=True)
    return FrozenJudgeResult(
        result[0], result[1], result[2], request, True, False, response
    )


def _validate_response(
    response: dict[str, Any],
    request: dict[str, Any],
    *,
    dispatched: bool,
) -> tuple[str, tuple[str, ...], str]:
    del dispatched
    unknown = set(response) - {"verdict", "evidence_refs"}
    if unknown:
        return "unresolved", (), "judge_response_invalid"
    verdict = response.get("verdict")
    if verdict not in {"supported", "contradicted", "unresolved"}:
        return "unresolved", (), "judge_response_invalid"
    refs = response.get("evidence_refs", [])
    if not isinstance(refs, list) or not all(
        isinstance(ref, str) and ref for ref in refs
    ):
        return "unresolved", (), "judge_evidence_invalid"
    references = tuple(refs)
    if verdict in {"supported", "contradicted"}:
        if not references:
            return "unresolved", references, "judge_support_missing"
        for reference in references:
            try:
                value = _resolve_evidence_ref(request["evidence"], reference)
            except (KeyError, IndexError, TypeError, ValueError):
                return "unresolved", references, "judge_support_unresolved"
            if not _usable_support(request["evidence"], reference, value):
                return "unresolved", references, "judge_support_unresolved"
    return verdict, references, "judge_completed"


def _usable_support(evidence: dict[str, Any], reference: str, value: Any) -> bool:
    """Require support references to point at captured, interpretable evidence."""

    if value is None:
        return False
    root = reference.lstrip("/").split("/", 1)[0].split("[", 1)[0]
    availability = evidence.get("availability")
    completeness = evidence.get("completeness")
    if isinstance(availability, dict) and availability.get(root) != "captured":
        return False
    specific_item = "[" in reference or (
        reference.startswith("/") and any(part.isdigit() for part in reference.split("/")[2:])
    )
    if (
        not specific_item
        and isinstance(completeness, dict)
        and completeness.get(root) in {"unknown", "partial"}
    ):
        return False
    if root == "messages":
        if isinstance(value, list):
            return bool(value) and all(
                isinstance(item, dict) and isinstance(item.get("content"), str)
                for item in value
            )
        return isinstance(value, dict) and isinstance(value.get("content"), str)
    if root == "tool_calls":
        if isinstance(value, list):
            return bool(value) and all(
                isinstance(item, dict) and not item.get("parse_errors")
                for item in value
            )
        return isinstance(value, dict) and not value.get("parse_errors")
    return True


def _resolve_evidence_ref(evidence: dict[str, Any], reference: str) -> Any:
    if reference in evidence:
        return evidence[reference]
    current: Any = evidence
    if reference.startswith("/"):
        parts = reference.split("/")[1:]
        for part in parts:
            current = _step(current, part.replace("~1", "/").replace("~0", "~"))
        return current
    tokens = []
    for token in reference.replace("[", ".").replace("]", "").split("."):
        if token:
            tokens.append(token)
    if not tokens:
        raise ValueError(f"evidence reference does not resolve: {reference}")
    for token in tokens:
        current = _step(current, token)
    return current


def _step(current: Any, part: str) -> Any:
    if isinstance(current, dict) and part in current:
        return current[part]
    if isinstance(current, list) and part.isdigit() and int(part) < len(current):
        return current[int(part)]
    raise KeyError(part)


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


__all__ = ["FrozenJudgeResult", "evaluate_frozen_judge"]
