"""The package-declared, bounded semantic judge seam."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

JUDGE_VERDICTS = frozenset({"supported", "contradicted", "unresolved"})
_MISSING = object()


@dataclass(frozen=True)
class FrozenJudgeResult:
    verdict: str
    evidence_refs: tuple[str, ...]
    reason: str
    request: dict[str, Any] | None
    dispatched: bool
    reused: bool = False
    output: Any = None
    evidence_ref_mappings: tuple[dict[str, str], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        value = {
            "verdict": self.verdict,
            "evidence_refs": list(self.evidence_refs),
            "reason": self.reason,
            "request": self.request,
            "output": self.output,
            "dispatched": self.dispatched,
            "reused": self.reused,
        }
        if self.evidence_ref_mappings:
            value["evidence_ref_mappings"] = [
                dict(mapping) for mapping in self.evidence_ref_mappings
            ]
        return value


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
            result[3],
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
        result[0], result[1], result[2], request, True, False, response, result[3]
    )


def normalize_evidence_packet(
    evidence: dict[str, Any],
    *,
    judge_enabled: bool,
) -> dict[str, Any]:
    """Return the detector-facing packet with a closed judge projection."""

    if not isinstance(evidence, dict):
        raise ValueError("evidence packet must be an object")
    packet = dict(evidence)
    if not judge_enabled:
        packet.pop("judge", None)
        return packet
    packet["judge"] = _normalize_judge(
        evidence["judge"] if "judge" in evidence else _MISSING,
        evidence,
    )
    return packet


def _normalize_judge(value: Any, evidence: dict[str, Any]) -> dict[str, Any]:
    if value is _MISSING:
        return _unresolved_judge("judge_missing")
    if not isinstance(value, dict):
        return _unresolved_judge("judge_invalid")
    verdict = value.get("verdict")
    refs = value.get("evidence_refs")
    if verdict not in JUDGE_VERDICTS:
        return _unresolved_judge("judge_response_invalid")
    if not isinstance(refs, list) or not all(
        isinstance(ref, str) and ref.strip() for ref in refs
    ):
        return _unresolved_judge("judge_evidence_invalid")
    references = list(refs)
    if verdict in {"supported", "contradicted"}:
        references = [
            _map_message_id_reference(evidence, reference)[0]
            for reference in references
        ]
        if not references:
            return _unresolved_judge("judge_support_missing", references)
        for reference in references:
            try:
                support = _resolve_evidence_ref(evidence, reference)
            except (KeyError, IndexError, TypeError, ValueError):
                return _unresolved_judge("judge_support_unresolved", references)
            if not _usable_support(evidence, reference, support):
                return _unresolved_judge("judge_support_unresolved", references)
    reason = value.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        reason = "judge_completed"
    if verdict == "unresolved":
        return _unresolved_judge(reason)
    return {
        "verdict": verdict,
        "evidence_refs": references,
        "reason": reason,
    }


def _unresolved_judge(
    reason: str,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    del evidence_refs
    return {
        "verdict": "unresolved",
        "evidence_refs": [],
        "reason": reason,
    }


def _validate_response(
    response: dict[str, Any],
    request: dict[str, Any],
    *,
    dispatched: bool,
) -> tuple[str, tuple[str, ...], str, tuple[dict[str, str], ...]]:
    del dispatched
    unknown = set(response) - {"verdict", "evidence_refs"}
    if unknown:
        return "unresolved", (), "judge_response_invalid", ()
    verdict = response.get("verdict")
    if verdict not in {"supported", "contradicted", "unresolved"}:
        return "unresolved", (), "judge_response_invalid", ()
    refs = response.get("evidence_refs", [])
    if not isinstance(refs, list) or not all(
        isinstance(ref, str) and ref.strip() for ref in refs
    ):
        return "unresolved", (), "judge_evidence_invalid", ()
    if verdict == "unresolved":
        return "unresolved", (), "judge_completed", ()
    mappings: list[dict[str, str]] = []
    normalized_refs: list[str] = []
    for reference in refs:
        normalized, mapping = _map_message_id_reference(
            request["evidence"], reference
        )
        normalized_refs.append(normalized)
        if mapping is not None:
            mappings.append(mapping)
    references = tuple(normalized_refs)
    if verdict in {"supported", "contradicted"}:
        if not references:
            return "unresolved", (), "judge_support_missing", tuple(mappings)
        for reference in references:
            try:
                value = _resolve_evidence_ref(request["evidence"], reference)
            except (KeyError, IndexError, TypeError, ValueError):
                return "unresolved", (), "judge_support_unresolved", tuple(mappings)
            if not _usable_support(request["evidence"], reference, value):
                return "unresolved", (), "judge_support_unresolved", tuple(mappings)
    return verdict, references, "judge_completed", tuple(mappings)


def _map_message_id_reference(
    evidence: dict[str, Any], reference: str
) -> tuple[str, dict[str, str] | None]:
    """Map one unique captured message ID to its content path."""

    try:
        _resolve_evidence_ref(evidence, reference)
    except (KeyError, IndexError, TypeError, ValueError):
        messages = evidence.get("messages")
        if isinstance(messages, list):
            matches = [
                index
                for index, message in enumerate(messages)
                if isinstance(message, dict) and message.get("id") == reference
            ]
            if len(matches) == 1:
                path = f"messages[{matches[0]}].content"
                return path, {"from": reference, "to": path}
    return reference, None


def _usable_support(evidence: dict[str, Any], reference: str, value: Any) -> bool:
    """Require support references to point at captured, interpretable evidence."""

    if value is None:
        return False
    normalized = reference[2:] if reference.startswith("$.") else reference
    root = normalized.lstrip("/").split("/", 1)[0].split("[", 1)[0].split(".", 1)[0]
    availability = evidence.get("availability")
    completeness = evidence.get("completeness")
    if isinstance(availability, dict) and availability.get(root) != "captured":
        return False
    specific_item = "[" in normalized or (
        normalized.startswith("/")
        and any(part.isdigit() for part in normalized.split("/")[2:])
    )
    if (
        not specific_item
        and isinstance(completeness, dict)
        and completeness.get(root) in {"unknown", "partial"}
    ):
        return False
    if root == "messages":
        message_index = _message_content_index(reference)
        if message_index is not None:
            messages = evidence.get("messages")
            if not isinstance(messages, list) or message_index >= len(messages):
                return False
            message = messages[message_index]
            return (
                isinstance(message, dict)
                and isinstance(message.get("content"), str)
                and message["content"] == value
            )
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


def _message_content_index(reference: str) -> int | None:
    if reference.startswith("$."):
        reference = reference[2:]
    if reference.startswith("/"):
        parts = reference.split("/")
        if (
            len(parts) == 4
            and parts[1] == "messages"
            and parts[2].isdigit()
            and parts[3] == "content"
        ):
            return int(parts[2])
        return None
    if reference.startswith("messages[") and reference.endswith("].content"):
        index = reference[len("messages[") : -len("].content")]
        if index.isdigit():
            return int(index)
    return None


def _resolve_evidence_ref(evidence: dict[str, Any], reference: str) -> Any:
    if reference in evidence:
        return evidence[reference]
    current: Any = evidence
    if reference.startswith("/"):
        parts = reference.split("/")[1:]
        for part in parts:
            current = _step(current, part.replace("~1", "/").replace("~0", "~"))
        return current
    if reference.startswith("$."):
        reference = reference[2:]
    if not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*(?:\[[0-9]+\])?(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\])*",
        reference,
    ):
        raise ValueError(f"invalid evidence reference: {reference}")
    tokens = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)|\[([0-9]+)\]", reference)
    if not tokens:
        raise ValueError(f"evidence reference does not resolve: {reference}")
    for name, index in tokens:
        current = _step(current, name if name else index)
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


__all__ = [
    "FrozenJudgeResult",
    "JUDGE_VERDICTS",
    "evaluate_frozen_judge",
    "normalize_evidence_packet",
]
