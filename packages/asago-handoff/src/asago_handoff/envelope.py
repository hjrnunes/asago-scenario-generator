"""Compatibility facade over :mod:`asago_contracts_core.envelope`."""

from __future__ import annotations

from asago_contracts_core import envelope as _core
from asago_contracts_core.envelope import *  # noqa: F401,F403

__all__ = _core.__all__
