"""Load the JSON payloads that tests keep under ``tests/fixtures/``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def load_json_fixture(relative_path: str) -> Any:
    """Return a fresh copy of the JSON document at ``tests/fixtures/<relative_path>``.

    Every call parses the file again, so a test may mutate the result.
    """
    return json.loads((FIXTURES_DIR / relative_path).read_text(encoding="utf-8"))
