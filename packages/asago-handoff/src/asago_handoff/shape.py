"""Compatibility facade over :mod:`asago_contracts_core.shape`."""

from __future__ import annotations

from asago_contracts_core import shape as _core
from asago_contracts_core.shape import *  # noqa: F401,F403

__all__ = _core.__all__
