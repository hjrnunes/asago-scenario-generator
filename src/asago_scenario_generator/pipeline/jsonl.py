"""Shared JSON Lines persistence helpers."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def append_jsonl(
    entries: Sequence[dict[str, Any]],
    path: Path,
    *,
    lock: Any | None = None,
) -> None:
    """Append entries to a JSONL file, creating its parent directory."""
    if not entries:
        return

    def write() -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            for entry in entries:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    if lock is None:
        write()
    else:
        with lock:
            write()
