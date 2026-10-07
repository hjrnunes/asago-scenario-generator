"""Shared test builders moved out of test modules."""

from __future__ import annotations


def _base_stage1_data(**overrides) -> dict:
    """Minimal valid Stage1Profile payload (no zones_active field)."""
    data = {
        "has_persistent_memory": False,
        "multi_agent": False,
        "hitl": False,
        "entry_points": ["user input (input)"],
        "confidence": "high",
    }
    data.update(overrides)
    return data
