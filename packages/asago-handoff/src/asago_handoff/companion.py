"""Compatibility facade over :mod:`asago_contracts_core.companion`."""

from __future__ import annotations

from asago_contracts_core import companion as _core
from asago_contracts_core.companion import *  # noqa: F401,F403

__all__ = _core.__all__
