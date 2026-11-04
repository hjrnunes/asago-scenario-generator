"""Compatibility facade over :mod:`asago_contracts_core.violation`."""

from __future__ import annotations

from asago_contracts_core import violation as _core
from asago_contracts_core.violation import *  # noqa: F401,F403

__all__ = _core.__all__
