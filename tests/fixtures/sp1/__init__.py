"""Canonical SP1 payloads shared by the unit tests and the acceptance runtime.

Each YAML file holds named variants of one payload. Callers receive a deep
copy, so a test may edit its payload without affecting the next caller.
"""

from __future__ import annotations

from copy import deepcopy
from functools import cache
from pathlib import Path
from typing import Any

import yaml

_DIRECTORY = Path(__file__).resolve().parent


@cache
def _read(name: str) -> dict[str, Any]:
    return yaml.safe_load((_DIRECTORY / f"{name}.yaml").read_text(encoding="utf-8"))


def load_sp1_fixture(name: str, variant: str = "default") -> Any:
    """Return a fresh copy of one named variant of an SP1 payload."""
    return deepcopy(_read(name)[variant])
