"""Helpers shared by the stages that call a model adapter."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def call_with_feedback(
    method: Callable[..., Any], request: Any, feedback: str | None
) -> Any:
    """Call one adapter stage, passing a bounded schema correction if any."""
    if feedback is None:
        return method(request)
    return method(request, correction_feedback=feedback)
