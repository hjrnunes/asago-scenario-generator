"""Compatibility facade over :mod:`asago_contracts_core.condition_eval`."""

from __future__ import annotations

from asago_contracts_core import condition_eval as _core
from asago_contracts_core.condition_eval import *  # noqa: F401,F403

__all__ = _core.__all__
