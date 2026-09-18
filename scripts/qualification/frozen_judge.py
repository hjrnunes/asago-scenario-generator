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

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "evidence_refs": list(self.evidence_refs),
            "reason": self.reason,
            "request": self.request,
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
        "evidence": evidence,
    }
    key = _digest(request)
    if reuse and key in reuse:
        saved = reuse[key]
        return FrozenJudgeResult(
            saved.get("verdict", "unresolved"),
            tuple(saved.get("evidence_refs", [])),
            "judge_reused",
            request,
            False,
            True,
        )
    if client is None:
        return FrozenJudgeResult("unresolved", (), "judge_unavailable", request, False)
    try:
        response = client(request)
    except Exception as exc:  # pragma: no cover - transport boundary
        return FrozenJudgeResult(
            "unresolved", (), f"judge_failed:{type(exc).__name__}", request, True
        )
    if not isinstance(response, dict) or response.get("verdict") not in {
        "supported",
        "contradicted",
        "unresolved",
    }:
        return FrozenJudgeResult(
            "unresolved", (), "judge_response_invalid", request, True
        )
    refs = response.get("evidence_refs", [])
    if not isinstance(refs, list) or not all(
        isinstance(ref, str) and ref for ref in refs
    ):
        return FrozenJudgeResult(
            "unresolved", (), "judge_evidence_invalid", request, True
        )
    return FrozenJudgeResult(
        response["verdict"], tuple(refs), "judge_completed", request, True
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


__all__ = ["FrozenJudgeResult", "evaluate_frozen_judge"]
