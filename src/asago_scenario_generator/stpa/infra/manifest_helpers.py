"""Shared helpers for run manifest construction.

Extracted from ``scenario_prod/run.py`` and ``threat_enum/run.py`` to
eliminate duplication of ``_hash_model`` and ``_count_calls_by_stage``.
"""

from __future__ import annotations

import hashlib
import json
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


def count_calls_by_stage(run_dir: Path) -> dict[str, dict[str, int]]:
    """Count calls by stage from ``calls.jsonl``.

    Args:
        run_dir: Directory containing ``calls.jsonl``.

    Returns:
        A dict mapping stage label to ``{"call_count": int, "total_tokens": int}``.
        Returns an empty dict if the file does not exist.
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
        counts[stage]["call_count"] += 1
        counts[stage]["total_tokens"] += (entry.get("prompt_tokens") or 0) + (
            entry.get("completion_tokens") or 0
        )

    return counts
