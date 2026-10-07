"""Shared helpers for run manifest construction.

Provides the model hashing and per-stage call counting that the STPA stage
runners record in their manifests.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

__all__ = ["hash_model", "count_calls_by_stage"]


def hash_model(model: Any) -> str:
    """Compute SHA-256 hash of a Pydantic model's YAML representation.

    Args:
        model: A Pydantic model (or any object with ``model_dump``).

    Returns:
        A hex SHA-256 digest string.
    """
    content = yaml.dump(
        model.model_dump(mode="json", exclude_none=True),
        default_flow_style=False,
        sort_keys=True,
        allow_unicode=True,
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _entry_token_total(entry: Mapping[str, Any]) -> int:
    """Sum a call entry's token counters, treating absent values as zero."""
    return (entry.get("prompt_tokens") or 0) + (entry.get("completion_tokens") or 0)


def _request_not_sent(entry: Mapping[str, Any]) -> bool:
    """Tell whether a call-log entry records a request that was never sent.

    Every entry carries ``provider_request: true``, so the log marks an
    unsent request only through these two signals:

    * the prompt preflight blocked the prompt
      (``prompt_preflight.provider_call_allowed`` is false), or
    * the entry is a failure without a ``failure_class``. Only the
      post-dispatch failure logger sets ``failure_class``; the obligation
      adapter's own preflight and the local assembly steps log failures
      without it.
    """
    preflight = entry.get("prompt_preflight") or {}
    if preflight.get("provider_call_allowed") is False:
        return True
    return entry.get("success") is False and entry.get("failure_class") is None


def count_calls_by_stage(run_dir: Path) -> dict[str, dict[str, int]]:
    """Count the requests sent by stage from ``calls.jsonl``.

    Args:
        run_dir: Directory containing ``calls.jsonl``.

    Returns:
        A dict mapping stage label to ``{"call_count": int, "total_tokens": int}``.
        ``call_count`` counts the entries of requests that were sent, so a
        prompt the preflight blocked adds nothing; a stage whose entries were
        all blocked reports 0. Returns an empty dict if the file does not exist.
    """
    calls_file = run_dir / "calls.jsonl"
    if not calls_file.exists():
        return {}

    counts: dict[str, dict[str, int]] = {}
    for line in calls_file.read_text().splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        stage = entry.get("stage", "unknown")
        if stage not in counts:
            counts[stage] = {"call_count": 0, "total_tokens": 0}
        counts[stage]["call_count"] += not _request_not_sent(entry)
        counts[stage]["total_tokens"] += _entry_token_total(entry)

    return counts
