"""Compatibility facade over :mod:`asago_contracts_core.conformance`."""

from __future__ import annotations

from asago_contracts_core import conformance as _core
from asago_contracts_core.conformance import *  # noqa: F401,F403

__all__ = _core.__all__
