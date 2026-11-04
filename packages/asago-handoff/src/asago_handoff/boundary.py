"""Compatibility facade over :mod:`asago_contracts_core.boundary`."""

from __future__ import annotations

from asago_contracts_core import boundary as _core
from asago_contracts_core.boundary import *  # noqa: F401,F403

__all__ = _core.__all__
