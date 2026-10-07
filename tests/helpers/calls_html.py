"""Shared test builders moved out of test modules."""

from __future__ import annotations

import json
from pathlib import Path


def _write_calls_jsonl(path: Path, entries: list[dict]) -> Path:
    with path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")
    return path
