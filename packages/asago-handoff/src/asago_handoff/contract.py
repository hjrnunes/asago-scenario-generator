"""Compatibility facade over :mod:`asago_contracts_core.contract`."""

from __future__ import annotations

from asago_contracts_core import contract as _core
from asago_contracts_core.contract import *  # noqa: F401,F403

__all__ = _core.__all__
