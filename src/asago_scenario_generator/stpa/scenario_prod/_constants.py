"""Constants for the SP3 Scenario Production package.

This module exists so that every sub-module can import ``PROMPTS_DIR``
without creating a circular dependency through ``__init__``.

No other modules are imported here — this is a leaf module.
"""

from __future__ import annotations

from pathlib import Path

PROMPTS_DIR: Path = Path(__file__).parent / "prompts"
