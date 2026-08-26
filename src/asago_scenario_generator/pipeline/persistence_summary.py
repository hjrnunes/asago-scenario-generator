"""Semantic-generation summary projection."""

from __future__ import annotations

from typing import Any

from .persistence_journal import FinalizationInventoryV1


def _semantic_outcome(semantic: Any) -> tuple[str, list[str]]:
    if semantic is None:
        return "missing_semantic_evidence", []
    attempts = semantic.get("attempts", [])
    latest = attempts[-1] if attempts else {}
    outcome = str(latest.get("result") or "missing_attempt_result")
    warnings = [str(value) for value in semantic.get("warnings", [])]
    return outcome, warnings


def _stage_record(item: object) -> tuple[dict[str, Any], str, str, list[str]]:
    carrier = item.call if item.call is not None else item.failure
    semantic = carrier.semantic_evidence if carrier is not None else None
    outcome, warnings = _semantic_outcome(semantic)
    record = {
        "candidate_id": item.candidate_id,
        "stage": item.stage.value,
        "invocation_index": item.invocation_index,
        "outcome": outcome,
        "semantic_evidence": semantic,
    }
    return record, item.candidate_id, item.stage.value, warnings


def _candidate_stage_entry(
    candidate_id: str, decisions: dict[str, object]
) -> dict[str, Any]:
    decision = decisions.get(candidate_id)
    return {
        "admitted": bool(decision and decision.admitted),
        "complete_provider_semantics": False,
        "presentation_fallbacks": [],
        "stages": {},
    }


def _fallback_warnings(warnings: list[str], existing: list[str]) -> list[str]:
    return [
        warning
        for warning in warnings
        if warning.startswith("presentation_fallback:") and warning not in existing
    ]


def _complete_provider_semantics(
    candidate: dict[str, Any], required_stages: tuple[str, ...]
) -> bool:
    return all(
        candidate["stages"].get(stage) == "accepted" for stage in required_stages
    )


def build_semantic_generation_summary(
    inventory: FinalizationInventoryV1,
) -> dict[str, Any]:
    """Derive the bounded manifest view from finalization authority."""
    required_stages = ("actor", "narrative", "tree", "behavior")
    decisions = {item.candidate_id: item for item in inventory.admission_decisions}
    records: list[dict[str, Any]] = []
    candidates: dict[str, dict[str, Any]] = {}
    for item in sorted(inventory.stage_attempts, key=lambda value: value.sequence):
        record, candidate_id, stage_name, warnings = _stage_record(item)
        records.append(record)
        candidate = candidates.setdefault(
            candidate_id, _candidate_stage_entry(candidate_id, decisions)
        )
        candidate["stages"][stage_name] = record["outcome"]
        candidate["presentation_fallbacks"].extend(
            _fallback_warnings(warnings, candidate["presentation_fallbacks"])
        )
    for candidate in candidates.values():
        candidate["complete_provider_semantics"] = _complete_provider_semantics(
            candidate, required_stages
        )
    return {
        "schema_version": "1",
        "required_stages": list(required_stages),
        "candidates": candidates,
        "stage_records": records,
    }
