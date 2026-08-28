"""Constants for the SP1 System Model package.

This module exists so that :mod:`system_model.__init__` and every
sub-module can import ``PROMPTS_DIR`` without creating a circular
dependency through ``__init__``.

No other modules are imported here — this is a leaf module.
"""

from __future__ import annotations

from pathlib import Path

PROMPTS_DIR: Path = Path(__file__).parent / "prompts"
