"""Separate, pre-dispatch ledgers for downstream request categories."""

from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic
from typing import Any


@dataclass
class RequestLedger:
    category: str
    dispatches: list[dict[str, Any]] = field(default_factory=list)

    def before_dispatch(self, **record: Any) -> dict[str, Any]:
        """Append a dispatch record before a caller invokes its transport."""

        item = {
            "category": self.category,
            "sequence": len(self.dispatches) + 1,
            "started_monotonic": monotonic(),
        }
        item.update(record)
        self.dispatches.append(item)
        return item

    def complete(self, record: dict[str, Any], **updates: Any) -> None:
        record.update(updates)

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "dispatches": list(self.dispatches),
            "total": len(self.dispatches),
        }


def record_discovery_request(
    ledger: RequestLedger,
    *,
    method: str,
    path: str,
    purpose: str = "gateway_model_discovery",
    started_at: str | None = None,
    duration_ms: float | None = None,
) -> dict[str, Any]:
    """Record only safe local discovery metadata, never request headers."""

    record = ledger.before_dispatch(
        method=method,
        path=path,
        purpose=purpose,
        body_present=False,
        prompt_present=False,
        target_data_present=False,
        model_id_present=False,
    )
    if started_at is not None:
        record["started_at"] = started_at
    if duration_ms is not None:
        record["duration_ms"] = duration_ms
    return record


def gateway_runtime_settings(*, refresh_models: bool = False) -> dict[str, Any]:
    """Return the bounded gateway setting that disables periodic refresh."""

    return {"refresh_models": bool(refresh_models)}


def mapped_garak_value(
    result: dict[str, Any] | None, *, runtime_status: str
) -> int | None:
    """Map rich detector outcomes only after completed detector execution."""

    if runtime_status != "completed" or not isinstance(result, dict):
        return None
    return {"detected": 1, "not_detected": 0, "inconclusive": None}.get(
        result.get("outcome")
    )


__all__ = [
    "RequestLedger",
    "gateway_runtime_settings",
    "mapped_garak_value",
    "record_discovery_request",
]
