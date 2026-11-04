"""The old import path for the target-discovery scanner; M9 removes it.

The scanner moved to the producer's ``asago-target-discovery`` workspace
member, which installs as ``asago_target_discovery``. This module keeps every
package-root name importable for one cycle. New code imports
``asago_target_discovery``.
"""

from __future__ import annotations

from typing import Any

import asago_target_discovery

__all__ = list(asago_target_discovery.__all__)


def __getattr__(name: str) -> Any:
    try:
        value = getattr(asago_target_discovery, name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *dir(asago_target_discovery)})
