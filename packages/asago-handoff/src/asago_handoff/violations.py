"""Compatibility facade over :mod:`asago_contracts_core.violations`."""

from __future__ import annotations

from asago_contracts_core import violations as _core
from asago_contracts_core.violations import *  # noqa: F401,F403

__all__ = _core.__all__
